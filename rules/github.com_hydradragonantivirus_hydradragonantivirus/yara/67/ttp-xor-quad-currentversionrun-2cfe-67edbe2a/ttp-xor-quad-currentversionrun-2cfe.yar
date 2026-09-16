rule TTP_XOR_QUAD_CurrentVersionRun_2cfe {
  strings:
    $key_2cfe = { 7f 91 [2] 5b 9f [2] 70 b3 [2] 5e 91 [2] 4a 8a [2] 45 90 [2] 5b 8d [2] 59 8c [2] 42 8a [2] 5e 8d [2] 42 a2 }

  condition:
    any of them
}