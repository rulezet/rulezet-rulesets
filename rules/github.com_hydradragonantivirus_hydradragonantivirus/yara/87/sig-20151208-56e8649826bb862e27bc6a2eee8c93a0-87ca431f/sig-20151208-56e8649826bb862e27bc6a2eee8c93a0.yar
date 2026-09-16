rule sig_20151208_56e8649826bb862e27bc6a2eee8c93a0 {
  meta:
    description = "datamaliciousorder - file 20151208_56e8649826bb862e27bc6a2eee8c93a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e1833580227d49111a310e3b1c91aad4d9428e6f1e11520fdc00ac6bf3e1f2"

  strings:
    $s1  = "function heMTzVE(gFJwpepPsodvStojIfNBYDhqpSwNlTcPHPIO) {return !isNaN(parseFloat(gFJwpepPsodvStojIfNBYDhqpSwNlTcPHPIO)) && isFin" ascii
    $s2  = "function heMTzVE(gFJwpepPsodvStojIfNBYDhqpSwNlTcPHPIO) {return !isNaN(parseFloat(gFJwpepPsodvStojIfNBYDhqpSwNlTcPHPIO)) && isFin" ascii
    $s3  = "PDsgJhHc[tzJUCXVfoil]=(-883+883)/504; while(true) { if(SPDsgJhHc[tzJUCXVfoil] > KLZJa[tzJUCXVfoil].length-(-3+230)/227) { break;" ascii
    $s4  = "nVUzc)}function gRhLF(HVetlWpZXvs,AQnaHsNwbxSkm,LmIPVIfj){xhpV=parseInt(HVetlWpZXvs,AQnaHsNwbxSkm);wVVhz=xhpV.toString(LmIPVIfj)" ascii
    $s5  = "push(\"47\");x.push(\"42\");x.push(\"112\");x.push(\"100\");x.push(\"109\");x.push(\"100\");x.push(\"56\");x.push(\"55\");x.push" ascii
    $s6  = "push(\"59\");x.push(\"13\");x.push(\"10\");x.push(\"118\");x.push(\"97\");x.push(\"114\");x.push(\"32\");x.push(\"105\");x.push(" ascii
    $s7  = "push(\"97\");W.push(\"107\");W.push(\"59\");W.push(\"32\");W.push(\"13\");W.push(\"10\");W.push(\"32\");W.push(\"32\");W.push(\"" ascii
    $s8  = "function lrULQrbMleRyWHpbjGUpCwVKKnWAMBWzdAijRGIMVYnsQVszpGFHks(YqjQBLjWjJqKZ,hIJRipZQzryAZW){ return SeSLzJsCyMoDY[gRhLF(YqjQBL" ascii
    $s9  = "function lrULQrbMleRyWHpbjGUpCwVKKnWAMBWzdAijRGIMVYnsQVszpGFHks(YqjQBLjWjJqKZ,hIJRipZQzryAZW){ return SeSLzJsCyMoDY[gRhLF(YqjQBL" ascii
    $s10 = "var SeSLzJsCyMoDY=[];for(CynVUzc=(-138+138)/360;CynVUzc<(53313+703)/422;CynVUzc++){SeSLzJsCyMoDY[CynVUzc]=String.fromCharCode(Cy" ascii
    $s11 = "function cVcKdCJwTbajjhaqH(KLZJa){ZfEvYLEbejT= '';for(tzJUCXVfoil=(-962+962)/161; tzJUCXVfoil < (795+671)/733; tzJUCXVfoil++) {S" ascii
    $s12 = "push(\"32\");W.push(\"61\");W.push(\"61\");W.push(\"32\");W.push(\"49\");W.push(\"41\");W.push(\"32\");W.push(\"32\");W.push(\"1" ascii
    $s13 = ";return wVVhz;}function hmqFGXGhgxwKBbY(beZDIRTvpkVBsqnyf){eval(beZDIRTvpkVBsqnyf)}" fullword ascii
    $s14 = "function OMnhSkXIrRp(FeftqVXm,ULXIAX){return FeftqVXm.split(ULXIAX)}" fullword ascii
    $s15 = "function cVcKdCJwTbajjhaqH(KLZJa){ZfEvYLEbejT= '';for(tzJUCXVfoil=(-962+962)/161; tzJUCXVfoil < (795+671)/733; tzJUCXVfoil++) {S" ascii
    $s16 = "push(\"60\");" fullword ascii
    $s17 = ";}} return ZfEvYLEbejT}" fullword ascii
    $s18 = "push(\"42\");W.push(\"74\");W.push(\"97\");W.push(\"49\");W.push(\"86\");W.push(\"50\");W.push(\"54\");W.push(\"111\");W.push(\"" ascii
    $s19 = "push(\"10\");x.push(\"118\");x.push(\"97\");x.push(\"114\");x.push(\"32\");x.push(\"106\");x.push(\"107\");x.push(\"122\");x.pus" ascii
    $s20 = "push(\"118\");W.push(\"113\");W.push(\"112\");W.push(\"46\");W.push(\"116\");W.push(\"121\");W.push(\"112\");W.push(\"101\");W.p" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}