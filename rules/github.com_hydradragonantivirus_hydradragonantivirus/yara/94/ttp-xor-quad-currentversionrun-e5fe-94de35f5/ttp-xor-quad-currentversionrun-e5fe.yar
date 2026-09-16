rule TTP_XOR_QUAD_CurrentVersionRun_e5fe {
  strings:
    $key_e5fe = { b6 91 [2] 92 9f [2] b9 b3 [2] 97 91 [2] 83 8a [2] 8c 90 [2] 92 8d [2] 90 8c [2] 8b 8a [2] 97 8d [2] 8b a2 }

  condition:
    any of them
}