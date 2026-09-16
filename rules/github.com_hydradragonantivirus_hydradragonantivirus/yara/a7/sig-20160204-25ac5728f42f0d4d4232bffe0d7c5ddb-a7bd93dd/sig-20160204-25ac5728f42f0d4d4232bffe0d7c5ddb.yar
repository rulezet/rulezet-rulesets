rule sig_20160204_25ac5728f42f0d4d4232bffe0d7c5ddb {
  meta:
    description = "datamaliciousorder - file 20160204_25ac5728f42f0d4d4232bffe0d7c5ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "356fc8dd762b206ae1807f7763f71151d710cd6116e84e4b061b3b610248b182"

  strings:
    $s1 = "yadu', 'HY3LN', '3') + 'tf' + ('MgwvjD', 'ob', 'ML', '.') + 'e' + ('osi', 'aR', 'nlZ', 'x') + 'e', false);" fullword ascii
    $s2 = "        aQD1WQpXN['ope' + ('4kSJ', '7Hfa', 'gaskWU', 'n') + '']('GET' , 'ht' + ('DHkRD', 'eI4Y', '8iRSNZ', 't') + 'p:' + ('9pj'," ascii
    $s3 = "'] = function() {" fullword ascii
    $s4 = "    a7RloYIDA= this['Act' + ('5oSBa', 'LNYX', '6bF', 'i') + 'v' + ('3QqEVX', '1RN', 'mh', 'e') + 'X' + ('npMZAg', 'nfIEl', 'kpIn" ascii
    $s5 = "    a7RloYIDA= this['Act' + ('5oSBa', 'LNYX', '6bF', 'i') + 'v' + ('3QqEVX', '1RN', 'mh', 'e') + 'X' + ('npMZAg', 'nfIEl', 'kpIn" ascii
    $s6 = "    aQD1WQpXN['onr' + ('hygy', 'UHnW', 'Xlu', 'e') + 'ad' + ('duj', 'tu8Oc7', '1vYHLf', 'y') + 's' + ('OHX', '4TQ2', 'kAq', 't')" ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}