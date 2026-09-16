rule TTP_XOR_WriteProcessMemory_999a {
  strings:
    $key_999a = { ce e8 [2] fc ca [2] fa ff [2] d4 ff [2] eb e3 }

  condition:
    any of them
}