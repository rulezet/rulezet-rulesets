rule TTP_XOR_QUAD_CurrentVersionRun_172e {
  strings:
    $key_172e = { 44 41 [2] 60 4f [2] 4b 63 [2] 65 41 [2] 71 5a [2] 7e 40 [2] 60 5d [2] 62 5c [2] 79 5a [2] 65 5d [2] 79 72 }

  condition:
    any of them
}