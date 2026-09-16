rule TTP_XOR_QUAD_CurrentVersionRun_380e {
  strings:
    $key_380e = { 6b 61 [2] 4f 6f [2] 64 43 [2] 4a 61 [2] 5e 7a [2] 51 60 [2] 4f 7d [2] 4d 7c [2] 56 7a [2] 4a 7d [2] 56 52 }

  condition:
    any of them
}