rule sig_20160315_b91ecf7655d0c6291fb8d80e0afd0cb6 {
  meta:
    description = "datamaliciousorder - file 20160315_b91ecf7655d0c6291fb8d80e0afd0cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51a1e11bd8de2e23b59e18166c50394e56ea0f8d55df81ec43cc388eefe995a5"

  strings:
    $s1 = "function ZjOZTdycoS(ljxg){WshShell[EHCRbVTPdj + MvGGId](ljxg, 0, 0);}" fullword ascii
    $s2 = "while (jsnFyiMyH.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function iQixrci(n){return cKvBFSxkqjpdVKa + jyxr + wHMMbDHXZRJ + VoVFzHRetT + JUsbsjn + VtYdkzGhbac + jkNTeSc;}" fullword ascii
    $s4 = "jsnFyiMyH[YGVeMp + XUXFeSvjvIx](oGThtnurOiRwHv, EHdOQ + lXHHkLJxcQdkulh + oKFyQlALMu + Nyl1 + ybKHVRJHWvLum + mrBTkzAoTI + tvcxz" ascii
    $s5 = "MYyf + fysogyBeRhJMTi + ftavQAAMczOmO + NenHcllye, false);" fullword ascii
    $s6 = "var Uqj = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}