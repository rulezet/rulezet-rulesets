rule TTP_XOR_QUAD_CurrentVersionRun_38fe {
  strings:
    $key_38fe = { 6b 91 [2] 4f 9f [2] 64 b3 [2] 4a 91 [2] 5e 8a [2] 51 90 [2] 4f 8d [2] 4d 8c [2] 56 8a [2] 4a 8d [2] 56 a2 }

  condition:
    any of them
}