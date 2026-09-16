rule TTP_XOR_WriteProcessMemory_acaf {
  strings:
    $key_acaf = { fb dd [2] c9 ff [2] cf ca [2] e1 ca [2] de d6 }

  condition:
    any of them
}