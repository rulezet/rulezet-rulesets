rule TTP_XOR_QUAD_CurrentVersionRun_390e {
  strings:
    $key_390e = { 6a 61 [2] 4e 6f [2] 65 43 [2] 4b 61 [2] 5f 7a [2] 50 60 [2] 4e 7d [2] 4c 7c [2] 57 7a [2] 4b 7d [2] 57 52 }

  condition:
    any of them
}