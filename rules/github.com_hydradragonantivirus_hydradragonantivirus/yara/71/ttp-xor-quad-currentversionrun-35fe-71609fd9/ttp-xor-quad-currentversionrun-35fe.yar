rule TTP_XOR_QUAD_CurrentVersionRun_35fe {
  strings:
    $key_35fe = { 66 91 [2] 42 9f [2] 69 b3 [2] 47 91 [2] 53 8a [2] 5c 90 [2] 42 8d [2] 40 8c [2] 5b 8a [2] 47 8d [2] 5b a2 }

  condition:
    any of them
}