rule TTP_XOR_QUAD_CurrentVersionRun_1229 {
  strings:
    $key_1229 = { 41 46 [2] 65 48 [2] 4e 64 [2] 60 46 [2] 74 5d [2] 7b 47 [2] 65 5a [2] 67 5b [2] 7c 5d [2] 60 5a [2] 7c 75 }

  condition:
    any of them
}