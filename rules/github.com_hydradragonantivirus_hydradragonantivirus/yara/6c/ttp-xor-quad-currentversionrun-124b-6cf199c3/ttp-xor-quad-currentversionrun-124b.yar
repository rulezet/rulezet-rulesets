rule TTP_XOR_QUAD_CurrentVersionRun_124b {
  strings:
    $key_124b = { 41 24 [2] 65 2a [2] 4e 06 [2] 60 24 [2] 74 3f [2] 7b 25 [2] 65 38 [2] 67 39 [2] 7c 3f [2] 60 38 [2] 7c 17 }

  condition:
    any of them
}