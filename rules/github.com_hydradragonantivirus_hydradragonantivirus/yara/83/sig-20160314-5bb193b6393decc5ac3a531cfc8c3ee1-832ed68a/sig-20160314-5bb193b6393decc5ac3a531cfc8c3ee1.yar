rule sig_20160314_5bb193b6393decc5ac3a531cfc8c3ee1 {
  meta:
    description = "datamaliciousorder - file 20160314_5bb193b6393decc5ac3a531cfc8c3ee1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "775eb3e0c6ca253f75cb0f724d0b978ff6826173f5a28da12af88d3aa63938b1"

  strings:
    $s1  = "zMpmsbufSUQdnF = WshShell[MPPXIZSiRkci + IQDOSHTk + JEHU + TcdvCLaJVVrWZL + GnaCOVcJUz + YjBJIUoKrKQwF + iVk + zFcxmnDWRq + EZv " ascii
    $s2  = "zMpmsbufSUQdnF = WshShell[MPPXIZSiRkci + IQDOSHTk + JEHU + TcdvCLaJVVrWZL + GnaCOVcJUz + YjBJIUoKrKQwF + iVk + zFcxmnDWRq + EZv " ascii
    $s3  = "lXljuNwJ.open(XiycwqVrSDz + MzDzmhxtIx + fGd, wwYlid + EeEKxal + QPmXmsyr + muLwF + QiuBJCVqZv + xJrhfquHrgi + Zyp + ibartzVRlMk" ascii
    $s4  = "while (lXljuNwJ.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s5  = "P + hUMm + TPNnbnYuyVkOT + qpdnZNDLSkMtsDi + ZTgtKPXeX + QJknBHbn + ByL + NUUDrJkFF + ooT + wsSQ, false);" fullword ascii
    $s6  = "var JEHU = \"nd\";" fullword ascii
    $s7  = "var poqQRYHcZgNfwr = new Date();" fullword ascii
    $s8  = "function coZRTMAGwWpO(n)" fullword ascii
    $s9  = "function UHWoT(fname)" fullword ascii
    $s10 = "return gTacGlTTpSlwcAk + PbhaGMdYg + kTpfBPDGPsmwY + bJeBaUH + VTBp + OiRHMcLIybvQfg + BFKx" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}