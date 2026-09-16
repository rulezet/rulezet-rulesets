rule sig_20160525_55fa08a2385fed30179b9d12ca6f7f34 {
  meta:
    description = "datamaliciousorder - file 20160525_55fa08a2385fed30179b9d12ca6f7f34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5246907ece66e532b46aced6265f55058f7841a32a4be1a492c55168a5bc6114"

  strings:
    $s1  = "ath.pow(Math.sin(714), 2) + Math.pow(Math.cos(714), 2) - 1))-852) | KwRZIfsyUhaDezeyOmtJEkiI<< (804 + Math.round((Math.pow(Math." ascii
    $s2  = ") + Math.pow(Math.cos(378), 2) - 1))-322) & 0xff;WreGgMlGLPdzvjeJBTwvf = cZIBCeOHfRAWqbIzEFZb>> (420 + Math.round((Math.pow(Math" ascii
    $s3  = "sin(965), 2) + Math.pow(Math.cos(965), 2) - 1))-792) | KrCpopptdHbLZrfWz<< (407 + Math.round((Math.pow(Math.sin(431), 2) + Math." ascii
    $s4  = "function LFWAp(zHlDEtGpwGKvO) {var jqfWDHHUDhmomWEEHW = NjfMufSNZwG.join(eycoDUCcugHqift[0]);var gzCfAcelH, WreGgMlGLPdzvjeJBTwv" ascii
    $s5  = "== (285 + Math.round((Math.pow(Math.sin(746), 2) + Math.pow(Math.cos(746), 2) - 1))-221)) LiFpIUnCbBz += yX(gzCfAcelH);else if (" ascii
    $s6  = "function xYpScvutprRlSZzfx(LDhVOysftfsWHZuBmTJc,ImdLuOGiaUChChcyQouXMxol){return LDhVOysftfsWHZuBmTJc.charAt(ImdLuOGiaUChChcyQou" ascii
    $s7  = "function xYpScvutprRlSZzfx(LDhVOysftfsWHZuBmTJc,ImdLuOGiaUChChcyQouXMxol){return LDhVOysftfsWHZuBmTJc.charAt(ImdLuOGiaUChChcyQou" ascii
    $s8  = "FrGMS(gzCfAcelH, WreGgMlGLPdzvjeJBTwvf);else LiFpIUnCbBz += DwUybCks(gzCfAcelH, WreGgMlGLPdzvjeJBTwvf, TakPkWccEsdUvG);} while (" ascii
    $s9  = "function yX(fwUtSjEjDsynoqlgSgACstT){return String.fromCharCode(fwUtSjEjDsynoqlgSgACstT);}" fullword ascii
    $s10 = "OviszlMIuBYVEvrAeiTG < zHlDEtGpwGKvO.length);return LiFpIUnCbBz;}" fullword ascii
    $s11 = "function BSGexJUmBFrGMS(gnWCQrhxMU,JABBaXLXCGtu){return String.fromCharCode(gnWCQrhxMU,JABBaXLXCGtu);}" fullword ascii
    $s12 = "function LFWAp(zHlDEtGpwGKvO) {var jqfWDHHUDhmomWEEHW = NjfMufSNZwG.join(eycoDUCcugHqift[0]);var gzCfAcelH, WreGgMlGLPdzvjeJBTwv" ascii
    $s13 = "function DwUybCks(FtCaNfxrGiMqpoOhfQHPz,bJqCGktnnGitURDqHVVdQ,YGcwCntJB){return String.fromCharCode(FtCaNfxrGiMqpoOhfQHPz,bJqCGk" ascii
    $s14 = "function CuCKDLs(JAtMojsVikb,VPpFvECADOzgVCYZReUlBIF){return JAtMojsVikb.indexOf(VPpFvECADOzgVCYZReUlBIF);}" fullword ascii
    $s15 = "function DwUybCks(FtCaNfxrGiMqpoOhfQHPz,bJqCGktnnGitURDqHVVdQ,YGcwCntJB){return String.fromCharCode(FtCaNfxrGiMqpoOhfQHPz,bJqCGk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}