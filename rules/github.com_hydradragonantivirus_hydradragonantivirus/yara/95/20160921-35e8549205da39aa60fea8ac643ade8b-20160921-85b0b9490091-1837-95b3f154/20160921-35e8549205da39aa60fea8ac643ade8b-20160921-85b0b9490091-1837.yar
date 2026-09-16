rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_85b0b9490091_1837 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash3       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash4       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash5       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1  = "nction f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){ret" ascii
    $s2  = "){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})" ascii
    $s3  = " f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s4  = "00(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\"" ascii
    $s5  = "nction f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){retur" ascii
    $s6  = "(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s7  = "(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";" ascii
    $s8  = "unction f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){ret" ascii
    $s9  = "return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(" ascii
    $s10 = "h\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}