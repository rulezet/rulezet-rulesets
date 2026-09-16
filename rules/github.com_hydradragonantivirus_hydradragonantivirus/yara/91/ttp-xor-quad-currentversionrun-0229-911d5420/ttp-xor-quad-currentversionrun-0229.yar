rule TTP_XOR_QUAD_CurrentVersionRun_0229 {
  strings:
    $key_0229 = { 51 46 [2] 75 48 [2] 5e 64 [2] 70 46 [2] 64 5d [2] 6b 47 [2] 75 5a [2] 77 5b [2] 6c 5d [2] 70 5a [2] 6c 75 }

  condition:
    any of them
}