rule TTP_XOR_QUAD_CurrentVersionRun_093e {
  strings:
    $key_093e = { 5a 51 [2] 7e 5f [2] 55 73 [2] 7b 51 [2] 6f 4a [2] 60 50 [2] 7e 4d [2] 7c 4c [2] 67 4a [2] 7b 4d [2] 67 62 }

  condition:
    any of them
}