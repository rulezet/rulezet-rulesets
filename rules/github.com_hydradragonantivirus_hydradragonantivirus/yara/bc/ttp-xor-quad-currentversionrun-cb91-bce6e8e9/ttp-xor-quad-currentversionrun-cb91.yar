rule TTP_XOR_QUAD_CurrentVersionRun_cb91 {
  strings:
    $key_cb91 = { 98 fe [2] bc f0 [2] 97 dc [2] b9 fe [2] ad e5 [2] a2 ff [2] bc e2 [2] be e3 [2] a5 e5 [2] b9 e2 [2] a5 cd }

  condition:
    any of them
}