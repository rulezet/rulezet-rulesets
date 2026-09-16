rule FE_Hunting_BADRABBIT {
        meta:version=".2"
        filetype="PE"
        author="ian.ahl @TekDefense & nicholas.carr @itsreallynick"
        reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
        date="2017-10-24"
        md5 = "b14d8faf7f0cbcfad051cefe5f39645f"
strings:
                $msg1 = "Incorrect password" nocase ascii wide
        $msg2 = "Oops! Your files have been encrypted." ascii wide
        $msg3 = "If you see this text, your files are no longer accessible." ascii wide
        $msg4 = "You might have been looking for a way to recover your files." ascii wide
        $msg5 = "Don't waste your time. No one will be able to recover them without our" ascii wide
        $msg6 = "Visit our web service at" ascii wide
        $msg7 = "Your personal installation key#1:" ascii wide
        $msg8 = "Run DECRYPT app at your desktop after system boot" ascii wide
        $msg9 = "Password#1" nocase ascii wide
        $msg10 = "caforssztxqzf2nm.onion" nocase ascii wide
        $msg11 = /partition (unbootable|not (found|mounted))/ nocase ascii wide

                $fref1 = "C:\\Windows\\cscc.dat" nocase ascii wide
        $fref2 = "\\\\.\\dcrypt" nocase ascii wide
        $fref3 = "Readme.txt" ascii wide
        $fref4 = "\\Desktop\\DECRYPT.lnk" nocase ascii wide
        $fref5 = "dispci.exe" nocase ascii wide
        $fref6 = "C:\\Windows\\infpub.dat" nocase ascii wide
                $meta1 = "http://diskcryptor.net/" nocase ascii wide
        $meta2 = "dispci.exe" nocase ascii wide
        $meta3 = "GrayWorm" ascii wide
        $meta4 = "viserion" nocase ascii wide
                $com1 = "ComSpec" ascii wide
        $com2 = "\\cmd.exe" nocase ascii wide
        $com3 = "schtasks /Create" nocase ascii wide
        $com4 = "schtasks /Delete /F /TN %ws" nocase ascii wide
condition:
        (uint16(0) == 0x5A4D)
        and
        (8 of ($msg*) and 3 of ($fref*) and 2 of ($com*))
        or
        (all of ($meta*) and 8 of ($msg*))
    }