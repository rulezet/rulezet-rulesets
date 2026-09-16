rule TTP_XOR_QUAD_CurrentVersionRun_fcf2 {
  strings:
    $key_fcf2 = { af 9d [2] 8b 93 [2] a0 bf [2] 8e 9d [2] 9a 86 [2] 95 9c [2] 8b 81 [2] 89 80 [2] 92 86 [2] 8e 81 [2] 92 ae }

  condition:
    any of them
}