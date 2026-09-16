rule sig_20160525_7f963fb84df23d2eef3cad6a4cd4126c {
  meta:
    description = "datamaliciousorder - file 20160525_7f963fb84df23d2eef3cad6a4cd4126c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef27af90f1301bdb35bdc8be0f1b3beb59ceb5879c4ba853e8e2abea7155d774"

  strings:
    $s1  = "Math.sin(445), 2) + Math.pow(Math.cos(445), 2) - 1))-140)) wgGPZStvNClNNi += FC(vadPSwPYkkZHYMaydcjbMM);else if (kOHGEsRGXgkCCnz" ascii
    $s2  = "th.cos(416), 2) - 1))-151) & 0xff;AJPrDXldHqxmhnHrLw = qIoJhoNFK>> (289 + Math.round((Math.pow(Math.sin(599), 2) + Math.pow(Math" ascii
    $s3  = "function vQQCldEoofkMMn(RASVGDfhZaDqV) {var ASbBUdmYUdh = PbEjKgZtuUSfRnDmJjvE.join(nVXJrnCDXKEEkGMYUUbhRqm[0]);var vadPSwPYkkZH" ascii
    $s4  = "function gyUPPzQYSRljLusIc(nRJcMuLkwYVppfoUmB,dZscZwIADpBxUnFVic){return nRJcMuLkwYVppfoUmB.charAt(dZscZwIADpBxUnFVic);}" fullword ascii
    $s5  = "function TVcflWNnnBl(dlgCkKbREBNTDEbPsXiHkEuY,CJzJfAoFhwwyHSfZDpnL){return dlgCkKbREBNTDEbPsXiHkEuY.indexOf(CJzJfAoFhwwyHSfZDpnL" ascii
    $s6  = "function vQQCldEoofkMMn(RASVGDfhZaDqV) {var ASbBUdmYUdh = PbEjKgZtuUSfRnDmJjvE.join(nVXJrnCDXKEEkGMYUUbhRqm[0]);var vadPSwPYkkZH" ascii
    $s7  = "function FC(elFyYtAHhuqdwcYeyTCb){return String.fromCharCode(elFyYtAHhuqdwcYeyTCb);}" fullword ascii
    $s8  = "function jPvZILVGGBXKAtNGdxzUpwX(rnoMcXJsfYRLlLHI,pgtjkaiLFjGPnBxUyzwxty){return String.fromCharCode(rnoMcXJsfYRLlLHI,pgtjkaiLFj" ascii
    $s9  = "XKAtNGdxzUpwX(vadPSwPYkkZHYMaydcjbMM, AJPrDXldHqxmhnHrLw);else wgGPZStvNClNNi += GezFslOUJtgVudsBjmlckh(vadPSwPYkkZHYMaydcjbMM, " ascii
    $s10 = "function TVcflWNnnBl(dlgCkKbREBNTDEbPsXiHkEuY,CJzJfAoFhwwyHSfZDpnL){return dlgCkKbREBNTDEbPsXiHkEuY.indexOf(CJzJfAoFhwwyHSfZDpnL" ascii
    $s11 = "function jPvZILVGGBXKAtNGdxzUpwX(rnoMcXJsfYRLlLHI,pgtjkaiLFjGPnBxUyzwxty){return String.fromCharCode(rnoMcXJsfYRLlLHI,pgtjkaiLFj" ascii
    $s12 = "function GezFslOUJtgVudsBjmlckh(XdDmYqkAss,GBjwLKWkKJX,ZiJgZDIGAieUoa){return String.fromCharCode(XdDmYqkAss,GBjwLKWkKJX,ZiJgZDI" ascii
    $s13 = "function GezFslOUJtgVudsBjmlckh(XdDmYqkAss,GBjwLKWkKJX,ZiJgZDIGAieUoa){return String.fromCharCode(XdDmYqkAss,GBjwLKWkKJX,ZiJgZDI" ascii
    $s14 = "AJPrDXldHqxmhnHrLw, LMduXHrOIrhAeembsL);} while (fPbMYwbrcWPOzo < RASVGDfhZaDqV.length);return wgGPZStvNClNNi;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}