rule TTP_XOR_QUAD_CurrentVersionRun_edfe {
  strings:
    $key_edfe = { be 91 [2] 9a 9f [2] b1 b3 [2] 9f 91 [2] 8b 8a [2] 84 90 [2] 9a 8d [2] 98 8c [2] 83 8a [2] 9f 8d [2] 83 a2 }

  condition:
    any of them
}