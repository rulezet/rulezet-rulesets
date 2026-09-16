rule TTP_XOR_QUAD_CurrentVersionRun_300e {
  strings:
    $key_300e = { 63 61 [2] 47 6f [2] 6c 43 [2] 42 61 [2] 56 7a [2] 59 60 [2] 47 7d [2] 45 7c [2] 5e 7a [2] 42 7d [2] 5e 52 }

  condition:
    any of them
}