rule TTP_XOR_QUAD_CurrentVersionRun_cb92 {
  strings:
    $key_cb92 = { 98 fd [2] bc f3 [2] 97 df [2] b9 fd [2] ad e6 [2] a2 fc [2] bc e1 [2] be e0 [2] a5 e6 [2] b9 e1 [2] a5 ce }

  condition:
    any of them
}