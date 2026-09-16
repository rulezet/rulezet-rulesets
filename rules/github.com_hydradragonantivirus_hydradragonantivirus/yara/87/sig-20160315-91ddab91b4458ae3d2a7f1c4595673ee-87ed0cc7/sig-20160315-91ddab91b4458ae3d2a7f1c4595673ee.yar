rule sig_20160315_91ddab91b4458ae3d2a7f1c4595673ee {
  meta:
    description = "datamaliciousorder - file 20160315_91ddab91b4458ae3d2a7f1c4595673ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd86d3e6e9787b77c259b9397e59e8f28ffb5b94e0e0198fa60cb171bfa1c267"

  strings:
    $s1 = "function ctp(pVIhYvVYtTG){WshShell[LZuSKtPi + TNkdE](pVIhYvVYtTG, 0, 0);}" fullword ascii
    $s2 = "while (dybwNHhWXoPdkj.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function QREUVfQNrlft(n){return XRBEUk + HebNkDSHGPiy + kZcrnYSOIh + RvUALqKsOpT + UZOYZiXCFZDxMx + rbono;}" fullword ascii
    $s4 = "dybwNHhWXoPdkj[UBZrfOTuynuk + MCgyPBRMVg](emzckoaCOJC, awjPkK + CXbrkRjx + udw + ZHlZmmWtDr + mAaJmJfI + upnrpsrsbhSxZ + kJicKF " ascii
    $s5 = "Os, false);" fullword ascii
    $s6 = "var HfeEIMOneY = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}