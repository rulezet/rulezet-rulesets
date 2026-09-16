rule TTP_XOR_QUAD_CurrentVersionRun_dee7 {
  strings:
    $key_dee7 = { 8d 88 [2] a9 86 [2] 82 aa [2] ac 88 [2] b8 93 [2] b7 89 [2] a9 94 [2] ab 95 [2] b0 93 [2] ac 94 [2] b0 bb }

  condition:
    any of them
}