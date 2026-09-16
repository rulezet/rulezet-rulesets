rule TTP_XOR_QUAD_CurrentVersionRun_126b {
  strings:
    $key_126b = { 41 04 [2] 65 0a [2] 4e 26 [2] 60 04 [2] 74 1f [2] 7b 05 [2] 65 18 [2] 67 19 [2] 7c 1f [2] 60 18 [2] 7c 37 }

  condition:
    any of them
}