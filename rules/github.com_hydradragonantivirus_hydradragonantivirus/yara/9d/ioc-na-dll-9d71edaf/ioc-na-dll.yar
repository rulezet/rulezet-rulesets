import "hash"
rule IOC_NA_dll {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 04:42:31"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "dll"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "3afd0ec9ff87802fecb70c64bf0c0b86081bd909b9b649f902931964d585632a" or
    hash.sha256(0, filesize) == "d6f843c7ea0e1bbef9b381b35d2e942b88f204c1a43de76011da57563f21c95e" or
    hash.sha256(0, filesize) == "379e01a20f66afe32b7792eab0bc3d97179ee0fcca919e4604769d6a6fc3c2e1" or
    hash.sha256(0, filesize) == "506bc39774eea82a02c20bce1ef02b751133eee9e512747c250d972124fef76b" or
    hash.sha256(0, filesize) == "ea44b39b32fd766f5a4c9b0d426451065e3ed6d9d977cddcb7cfacfcd82be47d" or
    hash.sha256(0, filesize) == "5cc6b31669023b1f74191cc76d25924fb652a19c92eb3bef80d176304b0cee1a" or
    hash.sha256(0, filesize) == "035243c99d29f9f785e7f76ac3e744c56c7386449ad51b1d7cce9c19380a487c" or
    hash.sha256(0, filesize) == "ba3b6093e676d0d4ed3832efc496ad3a1b7c24e9a27574520c7b54e84b93de32" or
    hash.sha256(0, filesize) == "cd12655ebbcfc6789326d27f125ee39ec47b49c93ffd3e80af11d308a917107d" or
    hash.sha256(0, filesize) == "1f0dd88879a0facb7ad1cec668a9c65bcf06ac1d69945989770f04740e1117a7" or
    hash.sha256(0, filesize) == "fd45836d17756388b7bf67083e5247fdbe2154149f4a9cf3d30fc8348e3020ac" or
    hash.sha256(0, filesize) == "e4f32b898bb95e747f9b11d1b7dd52a8a36e7116e66fa171eebed1bb290eabe5" or
    hash.sha256(0, filesize) == "af32907430cff27948a020b20e76c590d6561e1a9f7464d7071fc4d5c4db7b1d" or
    hash.sha256(0, filesize) == "080c2b0ebcaa675f7cc3087a62b458bd05829a5056b93b478b0c137140e613ed" or
    hash.sha256(0, filesize) == "c367c645711aeebb01f2332638dbad2b665bb9cc7e34fcc6c2eae91385da730d" or
    hash.sha256(0, filesize) == "98cd89574c41cd0f664b482c7964386b96987b8dac316860f4f02b351da8a77e" or
    hash.sha256(0, filesize) == "fd84fbbb02015979484e56ee1f8de94df66b7c031c8df094c25ee8d4189e2f62" or
    hash.sha256(0, filesize) == "5dce23221c5c4ce62fb33f2de5438ae15b86d796c39091cfb495ca01f8eb04c2" or
    hash.sha256(0, filesize) == "2eef4b05700162c4b8b9f00d8ef7b0d11e1e273219d30130561293bb429f1850" or
    hash.sha256(0, filesize) == "f4b90e1ceaa1c88458604f34205b55f5cc7bbd11dc9da6e5fb0b2dd20215774a" or
    hash.sha256(0, filesize) == "8383d1cf45e6dd5345dc5d6e7aff4dff75a5dac629a617cc08150924ab019fee" or
    hash.sha256(0, filesize) == "7b9c99c1aeb0681b96a38c5084658497d4ebd6a196f8618030cb034295d825b3" or
    hash.sha256(0, filesize) == "1f9a4fa0a9cb98637bf34cf919c0f964551b79abcce5621d7b165720aa45988c" or
    hash.sha256(0, filesize) == "f122b4ab576902c76b6f127399d6fa51c94fcc90a87c4f870acb6aa2c74fc2be" or
    hash.sha256(0, filesize) == "7dfc837c2da8c5a32150052a9876447170d8923b31409a3a1919d918027cae19" or
    hash.sha256(0, filesize) == "591d2575c173f07028f37e371da17f7727c78d31ab1578b222c976fa5fad2b3c" or
    hash.sha256(0, filesize) == "bc60d6b0dd2558c683f2db24c79187f1c870e35deb4dd5586965f49e2d24de33" or
    hash.sha256(0, filesize) == "f366d535c63702f7412cfe4ec1c63edc3dd86c44f2d42ce9e6cfd63cec78d930" or
    hash.sha256(0, filesize) == "b9a953af462e7c92a64aa70d6e596cd715b3e0cf5761bd76a80d8c252c45a38c" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}