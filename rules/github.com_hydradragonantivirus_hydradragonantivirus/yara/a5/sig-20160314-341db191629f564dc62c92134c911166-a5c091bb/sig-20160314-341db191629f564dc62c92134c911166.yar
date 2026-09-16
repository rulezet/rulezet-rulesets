rule sig_20160314_341db191629f564dc62c92134c911166 {
  meta:
    description = "datamaliciousorder - file 20160314_341db191629f564dc62c92134c911166.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b43ea808da93ea8a97b4639cf8c1bc7707e25066ed6f57c7287d130d75d6c550"

  strings:
    $s1 = "jowgwnptJBdM.open(TYYQq + WfbLDDuEgRVAf, kjlJMHEts + GMzEBPRGLVsh + bAHTz + OuWBnGcNZJhAEJ + gdjtQc + NdOsYUCRd + pmLQ + imdeQMR" ascii
    $s2 = "return rBkWut + qyZFSASf + ZedkckgqVMmnvSt + lRxcuRfkLBOuy + kWGMKftoBAW + fZOMInt + uQkBJoTMPuE" fullword ascii
    $s3 = "while (jowgwnptJBdM.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s4 = " + cwYSYuix + FiNJJcSFSVdIYcb + vZhvEPg + XPoUXnm + azHvltToVADPCHE + Oxvr + Fsdf, false);" fullword ascii
    $s5 = "function zCiuAW(fname)" fullword ascii
    $s6 = "var ueXiaB = new Date();" fullword ascii
    $s7 = "function tSl(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}