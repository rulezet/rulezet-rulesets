rule sig_20160514_691b74a61fce54f3a521c67024b5aeb3 {
  meta:
    description = "datamaliciousorder - file 20160514_691b74a61fce54f3a521c67024b5aeb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdb80d11c1a7d12143fa5ea5431fc989685aed6dc8b0a12160e7f319cac37a8e"

  strings:
    $s1  = "while (AFaI < BEpbOV - (222 - 220)) {" fullword ascii
    $s2  = "return OHYS;" fullword ascii
    $s3  = "function vfhDJn() {" fullword ascii
    $s4  = "return JPOXnxKi;" fullword ascii
    $s5  = "return dwJe;" fullword ascii
    $s6  = "function qeum(rtwjdld, kdkndmd) {" fullword ascii
    $s7  = "function GVOdk() {" fullword ascii
    $s8  = "return Cxhh;" fullword ascii
    $s9  = "function rtFD() {" fullword ascii
    $s10 = "function Lyx(DOytBqJ) {" fullword ascii
    $s11 = "return mpLpx;" fullword ascii
    $s12 = "return HXmGPZD;" fullword ascii
    $s13 = "return fsTh;" fullword ascii
    $s14 = "return XyZD;" fullword ascii
    $s15 = "return wRXEXoQm;" fullword ascii
    $s16 = "return RHZNv;" fullword ascii
    $s17 = "var dVoKfDc = String;" fullword ascii
    $s18 = "function JNVAs() {" fullword ascii
    $s19 = "return PbrSbiMp;" fullword ascii
    $s20 = "return deYpKqRL;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}