rule Trojan_Danger_Trojan_GenericKD_72853156_405_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_405_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d159b65e8ce3222af4b42a22a081f079eefbd54ce082ccaac63293d4d987da2"

  strings:
    $s1  = "Unable to connect to the target server." fullword ascii
    $s2  = "The download of the specified resource has failed." fullword ascii
    $s3  = "%s \"%s\",Compliance %s" fullword ascii
    $s4  = "The operation was timed out." fullword ascii
    $s5  = "jWill you allow this Web site to put a small file (called a cookie) on your computer for this session only?=Will you allow this " wide
    $s6  = "et session ha(bee" fullword ascii
    $s7  = "The system could not load the persisted data." fullword ascii
    $s8  = "No Internet session has been established." fullword ascii
    $s9  = "=0No Intern[{" fullword ascii
    $s10 = "A security problem occurred." fullword ascii
    $s11 = "Unable to instantiate the object." fullword ascii
    $s12 = "The server could not recognize the provided mime type." fullword ascii
    $s13 = "The specified protocol is unknown." fullword ascii
    $s14 = "The server did not understand the request, or the request was invalid." fullword ascii
    $s15 = "A redirection problem occured." fullword ascii
    $s16 = "No data is available for the requested resource." fullword ascii
    $s17 = "Authentication is required to access this resource." fullword ascii
    $s18 = "The system cannot locate the resource specified." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}