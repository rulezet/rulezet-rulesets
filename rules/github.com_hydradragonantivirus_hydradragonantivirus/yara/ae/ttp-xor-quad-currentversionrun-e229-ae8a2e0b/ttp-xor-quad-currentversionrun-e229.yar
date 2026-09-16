rule TTP_XOR_QUAD_CurrentVersionRun_e229 {
  strings:
    $key_e229 = { b1 46 [2] 95 48 [2] be 64 [2] 90 46 [2] 84 5d [2] 8b 47 [2] 95 5a [2] 97 5b [2] 8c 5d [2] 90 5a [2] 8c 75 }

  condition:
    any of them
}