rule TTP_XOR_QUAD_CurrentVersionRun_170e {
  strings:
    $key_170e = { 44 61 [2] 60 6f [2] 4b 43 [2] 65 61 [2] 71 7a [2] 7e 60 [2] 60 7d [2] 62 7c [2] 79 7a [2] 65 7d [2] 79 52 }

  condition:
    any of them
}