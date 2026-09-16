rule TTP_XOR_QUAD_CurrentVersionRun_ccf2 {
  strings:
    $key_ccf2 = { 9f 9d [2] bb 93 [2] 90 bf [2] be 9d [2] aa 86 [2] a5 9c [2] bb 81 [2] b9 80 [2] a2 86 [2] be 81 [2] a2 ae }

  condition:
    any of them
}