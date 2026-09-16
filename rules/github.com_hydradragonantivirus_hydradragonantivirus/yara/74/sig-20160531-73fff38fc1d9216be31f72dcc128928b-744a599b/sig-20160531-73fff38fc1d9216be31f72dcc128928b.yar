rule sig_20160531_73fff38fc1d9216be31f72dcc128928b {
  meta:
    description = "datamaliciousorder - file 20160531_73fff38fc1d9216be31f72dcc128928b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64072c7bebba4cfd5d858d07513cf21c24a7d0565d0ddd7260f82d565ecd6c05"

  strings:
    $s1  = "var paLqc=function(){return WScript.CreateObject(jNAbrJvHswy[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function oeCMNcDDjrRzNDZrU(sfGMiEQAKhRmtHFqtEaDk,vfCrPNCoJ){return sfGMiEQAKhRmtHFqtEaDk.charAt(vfCrPNCoJ);}" fullword ascii
    $s3  = "function POuIZDENhmnWa(IRcvKiLZIAGLyZVnNQRsWk,JyIiCyPKqYvyqHOfo){return IRcvKiLZIAGLyZVnNQRsWk.indexOf(JyIiCyPKqYvyqHOfo);}" fullword ascii
    $s4  = "function EeDkbyZB(JCdQlwsUktjJcwmznScOKsA,WqQNxAJUZsYKGb,LkpOnQEqXIaZRd){return String.fromCharCode(JCdQlwsUktjJcwmznScOKsA,WqQN" ascii
    $s5  = "];}return OlandkjsGw.substring(3,OlandkjsGw.length);}" fullword ascii
    $s6  = "(sLgqqvimdV,0x1,0x0)}function UIRRIlyxf(bENDPfLSSHy,oVrpddhhtbSXY,kAzEvBdU){var NIgFpKvGdt=bENDPfLSSHy.createtextfile(oVrpddhhtb" ascii
    $s7  = "function KrApplcMfAVX(){return paLqc.ExpandEnvironmentStrings(ctJaIoXYzk())}" fullword ascii
    $s8  = " 0xff;YPucMrftMhQESe = TmBPxJSYblkyZDk & 0xff;if (wiQRWSzCRtO == 64) CxCWy += Rbi(ezuoDCJ);else if (BbiPxVHqswcVkOmc == 64) CxCW" ascii
    $s9  = "SXY,true);NIgFpKvGdt.WriteLine(kAzEvBdU);NIgFpKvGdt.Close();}" fullword ascii
    $s10 = "function EeDkbyZB(JCdQlwsUktjJcwmznScOKsA,WqQNxAJUZsYKGb,LkpOnQEqXIaZRd){return String.fromCharCode(JCdQlwsUktjJcwmznScOKsA,WqQN" ascii
    $s11 = "function YRAKHFbbDiWnAMpQTPOoX(fufcmOt,RfrWeTaKG){return String.fromCharCode(fufcmOt,RfrWeTaKG);}" fullword ascii
    $s12 = ");} while (eOoOybFkQZntctmYCmUDE < nDpIxovsVcpIn.length);return CxCWy;}" fullword ascii
    $s13 = "(sLgqqvimdV,0x1,0x0)}function UIRRIlyxf(bENDPfLSSHy,oVrpddhhtbSXY,kAzEvBdU){var NIgFpKvGdt=bENDPfLSSHy.createtextfile(oVrpddhhtb" ascii
    $s14 = "var zahCGxZ=function(){return new ActiveXObject(jNAbrJvHswy[1]);}();" fullword ascii
    $s15 = "function WDfCIQaxcFesc(DjaXkxfLHngctR,sLgqqvimdV) {var DXJXHMkTDqG=[jNAbrJvHswy[15]];DjaXkxfLHngctR[DXJXHMkTDqG[0]]" fullword ascii
    $s16 = "y += YRAKHFbbDiWnAMpQTPOoX(ezuoDCJ, YwScHdbVwsbWvVWrWjaKt);else CxCWy += EeDkbyZB(ezuoDCJ, YwScHdbVwsbWvVWrWjaKt, YPucMrftMhQESe" ascii
    $s17 = "function Rbi(esOfRIthsnfmAfCqQYSqrMlT){return String.fromCharCode(esOfRIthsnfmAfCqQYSqrMlT);}" fullword ascii
    $s18 = "function cKCaafiChu(cSsQgaAoQG,KpZSlpEPdhQR,snjwMNrZDnxate){YHgCjmfta=cSsQgaAoQG.split(snjwMNrZDnxate);OlandkjsGw = jNAbrJvHswy[" ascii
    $s19 = "function ctJaIoXYzk(){return cKCaafiChu(jNAbrJvHswy[9],[1,5,7],jNAbrJvHswy[10]);}" fullword ascii
    $s20 = "function YSPQc(){return cKCaafiChu(jNAbrJvHswy[13],[0,3,6],jNAbrJvHswy[14]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}