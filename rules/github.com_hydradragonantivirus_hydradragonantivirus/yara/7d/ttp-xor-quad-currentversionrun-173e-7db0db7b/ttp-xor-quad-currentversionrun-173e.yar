rule TTP_XOR_QUAD_CurrentVersionRun_173e {
  strings:
    $key_173e = { 44 51 [2] 60 5f [2] 4b 73 [2] 65 51 [2] 71 4a [2] 7e 50 [2] 60 4d [2] 62 4c [2] 79 4a [2] 65 4d [2] 79 62 }

  condition:
    any of them
}