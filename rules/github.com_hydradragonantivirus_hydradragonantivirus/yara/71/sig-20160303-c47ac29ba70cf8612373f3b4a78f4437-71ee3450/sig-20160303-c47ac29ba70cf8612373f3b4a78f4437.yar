rule sig_20160303_c47ac29ba70cf8612373f3b4a78f4437 {
  meta:
    description = "datamaliciousorder - file 20160303_c47ac29ba70cf8612373f3b4a78f4437.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc466f55b2a79e99c7820f5144198ca981fadc16381dbeaac261f119d5ee8f74"

  strings:
    $s1  = "var zfwJf = \"TueJcT WAW pt.Shell qjkgKoV Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var qut = (luY + \"TTP\" + \" jRCnywp oQRps XML ream St eYtOVoOv AD iqeqMmq OD\").split(\" \");" fullword ascii
    $s3  = "var lz = true  , cFTW = qut[7] + \"\" + qut[9];" fullword ascii
    $s4  = "return cbjNyOD[0] + cbjNyOD[2] + cbjNyOD[4] + \".F\" + cbjNyOD[7] + cbjNyOD[9] + cbjNyOD[12] + cbjNyOD[14];" fullword ascii
    $s5  = "MOXYx.open(xIOCp,KzZlU,false);" fullword ascii
    $s6  = "var cbjNyOD = \"Sc pDiQfyj r EAyymDvFt ipting ZfyeVyq Tzt ile cTfeywZinjZPvO System Fx fxfND Obj JnxUOa ect AqaTZmX\".split(\" " ascii
    $s7  = "function exzB(MlKps,hOWTL) {" fullword ascii
    $s8  = "if (((new Date())>0,7353605888)) {" fullword ascii
    $s9  = "function TDWN(mtBYU) {" fullword ascii
    $s10 = "return LXFefUl" fullword ascii
    $s11 = "if (DDbLn == 1060-860){return true;} else {return false;}" fullword ascii
    $s12 = "RJx = P; break; " fullword ascii
    $s13 = "return UA.ExpandEnvironmentStrings(zfwJf[6]);" fullword ascii
    $s14 = "if (QNhfO > 197525-979){return true;} else {return false;}" fullword ascii
    $s15 = "function ndfG(DDbLn) {" fullword ascii
    $s16 = "function VcZm(yJgMb) {" fullword ascii
    $s17 = "function OpNZRaZYv(Wxqsp,JUAtW,KQtOy) {" fullword ascii
    $s18 = "function zEdr(EhEBN,XuqYA) {" fullword ascii
    $s19 = "function vLpLvTh(WLVs) {" fullword ascii
    $s20 = "function NOcV(QNhfO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}