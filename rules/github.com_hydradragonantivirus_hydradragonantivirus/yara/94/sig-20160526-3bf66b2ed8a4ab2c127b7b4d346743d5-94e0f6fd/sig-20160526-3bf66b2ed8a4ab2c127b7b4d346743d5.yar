rule sig_20160526_3bf66b2ed8a4ab2c127b7b4d346743d5 {
  meta:
    description = "datamaliciousorder - file 20160526_3bf66b2ed8a4ab2c127b7b4d346743d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b012c4cf69199c4e49bf01fddebb76f54df5ba235eff8e4683ca0261c78fbb"

  strings:
    $s1  = "function qmBTha(rREyRvHaLeXoP) {var fkgEWgtahqeqHqCSp = PoCHD.join(OXvsAotGAwWLYLGqIPwtF[0]);var IJvfPIinoqvNqTSajxtdcKW, XmYyqV" ascii
    $s2  = "ow(Math.cos(143), 2) - 1))-213)) CCjxEiQurJYbgCECqiAfVRI += pX(IJvfPIinoqvNqTSajxtdcKW);else if (nPHDVeHF == (412 + Math.round((" ascii
    $s3  = "function IvokzASdkRDktsCZXkIBcxF(rEBennFgPXAmAA,fzKKwAIkydjEDcpFclph){return rEBennFgPXAmAA.charAt(fzKKwAIkydjEDcpFclph);}" fullword ascii
    $s4  = "function JiNxKnJputpPakLdZEiN(htqtIlDOmcpuEqeLqc,GUTumeyyhyIXEu,oKjXCWM){return String.fromCharCode(htqtIlDOmcpuEqeLqc,GUTumeyyh" ascii
    $s5  = "function xYyyZRgaDh(kWMSTSSHLHbfoCo,iNhlmxVHnBMWQRDxkuLJ){return String.fromCharCode(kWMSTSSHLHbfoCo,iNhlmxVHnBMWQRDxkuLJ);}" fullword ascii
    $s6  = "(fLyqsiwunJ < rREyRvHaLeXoP.length);return CCjxEiQurJYbgCECqiAfVRI;}" fullword ascii
    $s7  = "function pX(rrgPcC){return String.fromCharCode(rrgPcC);}" fullword ascii
    $s8  = "W, XmYyqVVtAR);else CCjxEiQurJYbgCECqiAfVRI += JiNxKnJputpPakLdZEiN(IJvfPIinoqvNqTSajxtdcKW, XmYyqVVtAR, ByggclcpcDunW);} while " ascii
    $s9  = "function JiNxKnJputpPakLdZEiN(htqtIlDOmcpuEqeLqc,GUTumeyyhyIXEu,oKjXCWM){return String.fromCharCode(htqtIlDOmcpuEqeLqc,GUTumeyyh" ascii
    $s10 = "function yewUHuMoCIvnoraVujTMohOw(AIkhmiiIRfmMdZB,xvgWk){return AIkhmiiIRfmMdZB.indexOf(xvgWk);}" fullword ascii
    $s11 = "function qmBTha(rREyRvHaLeXoP) {var fkgEWgtahqeqHqCSp = PoCHD.join(OXvsAotGAwWLYLGqIPwtF[0]);var IJvfPIinoqvNqTSajxtdcKW, XmYyqV" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}