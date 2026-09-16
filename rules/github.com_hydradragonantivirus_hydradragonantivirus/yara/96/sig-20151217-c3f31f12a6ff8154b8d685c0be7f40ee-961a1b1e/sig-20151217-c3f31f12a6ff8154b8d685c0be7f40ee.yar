rule sig_20151217_c3f31f12a6ff8154b8d685c0be7f40ee {
  meta:
    description = "datamaliciousorder - file 20151217_c3f31f12a6ff8154b8d685c0be7f40ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "052ac03c257869348950e237dd0996d530daea5e8434465b6a5ad14a4176dd2b"

  strings:
    $s1  = "function duPXaafWXVSElJVro(TwKLm){JWbftoqZzbJ= '';tlHBqMeOZbE=Math.round((Math.pow(Math.sin(340), 2) + Math.pow(Math.cos(340), 2" ascii
    $s2  = "ow(Math.cos(999), 2) - 1)));} LPbnzjtBU[tlHBqMeOZbE]++;}tlHBqMeOZbE++;} return JWbftoqZzbJ}" fullword ascii
    $s3  = "th.pow(Math.cos(358), 2) - 1)); while(true) { if(LPbnzjtBU[tlHBqMeOZbE] > TwKLm[tlHBqMeOZbE].length-(291+511)/802) { break; } if" ascii
    $s4  = ") - 1));while(true){if (tlHBqMeOZbE >= (3236+808)/674){break;}LPbnzjtBU[tlHBqMeOZbE]=Math.round((Math.pow(Math.sin(358), 2) + Ma" ascii
    $s5  = "function duPXaafWXVSElJVro(TwKLm){JWbftoqZzbJ= '';tlHBqMeOZbE=Math.round((Math.pow(Math.sin(340), 2) + Math.pow(Math.cos(340), 2" ascii
    $s6  = "function iFtwzsFlxIhCUyyyYBsjWYdfFuYCXKvneCqUWfBQYYwrIUJRWkfrhN(yCEijqoPFxEXs,khZFxXNHavGJkR){ return ugFTgrD[FpYhQGvq[MMHxh(yCE" ascii
    $s7  = "function iFtwzsFlxIhCUyyyYBsjWYdfFuYCXKvneCqUWfBQYYwrIUJRWkfrhN(yCEijqoPFxEXs,khZFxXNHavGJkR){ return ugFTgrD[FpYhQGvq[MMHxh(yCE" ascii
    $s8  = "function VkUnjKz(BQCyhKlmtQOYBWMwzBggaOhBeSYamSXUZYmF) {return !YZwLFuuGXSN(hoRgTrDcuoUkKdp(BQCyhKlmtQOYBWMwzBggaOhBeSYamSXUZYmF" ascii
    $s9  = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s10 = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s11 = "function ErtsqTMDYICBRoGWT(OlVvluiSZH,gowwNnXAqv) {return parseInt(OlVvluiSZH,gowwNnXAqv);}" fullword ascii
    $s12 = "function hoRgTrDcuoUkKdp(BszuLgSEtvesBioIEYo) {return parseFloat(BszuLgSEtvesBioIEYo);}" fullword ascii
    $s13 = "function MMHxh(NOnXYVxEeOX,hONlBhboscQSb,nDqYDdhT){POzX=ErtsqTMDYICBRoGWT(NOnXYVxEeOX,hONlBhboscQSb);VQCrW=POzX.toString(nDqYDdh" ascii
    $s14 = "function weycEOZhMtBz(XTtKKKushbWzo) {return isFinite(XTtKKKushbWzo);}" fullword ascii
    $s15 = ",'<','F','V','N','&','W','<','0','<','z','Q','>','7','X','Y','B','X','1','>','%','Z','(','1','<','c','[','`','k','i','/',String." ascii
    $s16 = "function VkUnjKz(BQCyhKlmtQOYBWMwzBggaOhBeSYamSXUZYmF) {return !YZwLFuuGXSN(hoRgTrDcuoUkKdp(BQCyhKlmtQOYBWMwzBggaOhBeSYamSXUZYmF" ascii
    $s17 = "function S(VnmTfhuDpKjUpa,exztNXKVesfsI,IAdGkKWHhwB) {VnmTfhuDpKjUpa[exztNXKVesfsI]=IAdGkKWHhwB;}" fullword ascii
    $s18 = "function VPoUsTbEoIMTsbY(JuBQNOBKvXyylnWFz,KvXMjEdqcfCPhDLPTAolHdtzadQjpvtvXZ,puZAZWezglaGsZDXGyathrcDPZxUdSYGKFn){eval(JuBQNOBK" ascii
    $s19 = "function VPoUsTbEoIMTsbY(JuBQNOBKvXyylnWFz,KvXMjEdqcfCPhDLPTAolHdtzadQjpvtvXZ,puZAZWezglaGsZDXGyathrcDPZxUdSYGKFn){eval(JuBQNOBK" ascii
    $s20 = "T);return VQCrW;}" fullword ascii

  condition:
    uint16(0) == 0x7046 and
    8 of them
}