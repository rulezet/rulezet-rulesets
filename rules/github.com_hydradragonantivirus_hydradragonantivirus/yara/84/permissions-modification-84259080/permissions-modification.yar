rule Permissions_Modification {
	meta:
		mitre = "T1222 File and Directory Permissions Modification"
 	strings:
       		$a = "chmod -R"
		$b = "chmod -x"
		$c = "chmod 7"
		$c1 = "chmod 07"
		$c2 = "_chmod"
		$d = "chown -R"
		$e = "chown root"
       		$A = "chmod -R" base64
		$B = "chmod -x" base64
		$C = "chmod 7" base64
		$C1 = "chmod 07" base64
		$C2 = "_chmod" base64
		$D = "chown -R" base64
		$E = "chown root" base64
	condition:
 		any of them
}