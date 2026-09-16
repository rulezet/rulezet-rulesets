rule TTP_XOR_QUAD_CurrentVersionRun_f929 {
  strings:
    $key_f929 = { aa 46 [2] 8e 48 [2] a5 64 [2] 8b 46 [2] 9f 5d [2] 90 47 [2] 8e 5a [2] 8c 5b [2] 97 5d [2] 8b 5a [2] 97 75 }

  condition:
    any of them
}