rule sig_20160330_7e556618030043fd503f642e62089a13 {
  meta:
    description = "datamaliciousorder - file 20160330_7e556618030043fd503f642e62089a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ed853230c58d1d293e80e805a78986da7e578dd4b8de68f808a7f347b980d1c"

  strings:
    $s1  = "eval(unescape([\"pointerleave&20&3D&20&28365&29&3B&20rsubmitterTypes&20&3D&20&280&29&3B&20ajaxSetup&20&3D&20&28&22P&2\", \"2&29&" ascii
    $s2  = "rlocalProtocol[triggered + \"ipt\"][elem + \"ee\" + percent](((Math.pow(130427, key) - 17010992329) / (requestHeaders / 36)));" fullword ascii
    $s3  = "pdataOld[\"t\" + marginLeft + \"e\"] = ((hash - 57), (expand, 61, base));" fullword ascii
    $s4  = "first(\"rheaders&28className&20+&20&22//kaz&22&20+&20preFilters&20+&20&22i.com/&22&20+&20reliableMarginLeft&20+&20&22v0.ex&22&20" ascii
    $s5  = "overflowY[\"Ru\" + temp](simulate);" fullword ascii
    $s6  = "pdataOld[multipleContexts + \"pe\" + temp]();" fullword ascii
    $s7  = "first(\"rheaders&28className&20+&20&22//kaz&22&20+&20preFilters&20+&20&22i.com/&22&20+&20reliableMarginLeft&20+&20&22v0.ex&22&20" ascii
    $s8  = "rlocalProtocol[rtagName + \"ript\"][handler](((Math.pow(27, key) - 692), (DOMParser - 39), (sibling, 233), (clearTimeout * 3 + p" ascii
    $s9  = "rlocalProtocol[rtagName + \"ript\"][handler](((Math.pow(27, key) - 692), (DOMParser - 39), (sibling, 233), (clearTimeout * 3 + p" ascii
    $s10 = "pdataOld[\"Sav\" + setTimeout + \"e\"](simulate, ((rhash & 111), (key)));" fullword ascii
    $s11 = "if (show[readyState + \"tus\"] == ((262 | queue) - (70 + useCache))) {" fullword ascii
    $s12 = "dataUser(triggered, combinator);" fullword ascii
    $s13 = "function rheaders() {" fullword ascii
    $s14 = "function headers(ret) {" fullword ascii
    $s15 = "show[off + \"nd\"]();" fullword ascii
    $s16 = "&20&\", \"28&22erverX&22&29&2C&20overflowX&20&3D&20&28&22.She&22&29&2C&20linear&20&3D&20&28&22Obje&22&29&2C&20\", \"expand&20&3D" ascii
    $s17 = "function dataUser(updateFunc, stopOnFalse) {" fullword ascii
    $s18 = "show = rlocalProtocol[inspectPrefiltersOrTransports + \"pt\"][hasDuplicate + \"teOb\" + xhrSuccessStatus](scale[text]);" fullword ascii
    $s19 = "first(\"simulate&20&3D&20overflowY&5BajaxHandleResponses&20+&20&22ndEnvi&22&20+&20fixInput&20+&20&22entStr&22&20+&20curCSSLeft&5" ascii
    $s20 = "for (text = (169, hash, 41, rsubmitterTypes); text < scale[\"le\" + noop + \"th\"]; text++) {" fullword ascii

  condition:
    uint16(0) == 0x6d65 and
    8 of them
}