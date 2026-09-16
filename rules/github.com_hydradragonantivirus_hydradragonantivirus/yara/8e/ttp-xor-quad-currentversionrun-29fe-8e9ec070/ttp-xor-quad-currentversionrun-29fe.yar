rule TTP_XOR_QUAD_CurrentVersionRun_29fe {
  strings:
    $key_29fe = { 7a 91 [2] 5e 9f [2] 75 b3 [2] 5b 91 [2] 4f 8a [2] 40 90 [2] 5e 8d [2] 5c 8c [2] 47 8a [2] 5b 8d [2] 47 a2 }

  condition:
    any of them
}