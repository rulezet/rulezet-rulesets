rule TTP_XOR_WriteProcessMemory_faae {
  strings:
    $key_faae = { ad dc [2] 9f fe [2] 99 cb [2] b7 cb [2] 88 d7 }

  condition:
    any of them
}