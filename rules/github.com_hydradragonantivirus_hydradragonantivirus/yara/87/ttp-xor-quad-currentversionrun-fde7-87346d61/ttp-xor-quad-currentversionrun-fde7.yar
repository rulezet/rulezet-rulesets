rule TTP_XOR_QUAD_CurrentVersionRun_fde7 {
  strings:
    $key_fde7 = { ae 88 [2] 8a 86 [2] a1 aa [2] 8f 88 [2] 9b 93 [2] 94 89 [2] 8a 94 [2] 88 95 [2] 93 93 [2] 8f 94 [2] 93 bb }

  condition:
    any of them
}