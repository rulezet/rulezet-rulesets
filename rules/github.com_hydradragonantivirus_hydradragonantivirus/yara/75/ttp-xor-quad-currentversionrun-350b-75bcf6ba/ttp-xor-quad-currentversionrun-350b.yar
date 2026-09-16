rule TTP_XOR_QUAD_CurrentVersionRun_350b {
  strings:
    $key_350b = { 66 64 [2] 42 6a [2] 69 46 [2] 47 64 [2] 53 7f [2] 5c 65 [2] 42 78 [2] 40 79 [2] 5b 7f [2] 47 78 [2] 5b 57 }

  condition:
    any of them
}