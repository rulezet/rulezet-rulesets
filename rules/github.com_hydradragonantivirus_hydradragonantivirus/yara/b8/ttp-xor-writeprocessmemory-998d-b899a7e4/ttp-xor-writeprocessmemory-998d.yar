rule TTP_XOR_WriteProcessMemory_998d {
  strings:
    $key_998d = { ce ff [2] fc dd [2] fa e8 [2] d4 e8 [2] eb f4 }

  condition:
    any of them
}