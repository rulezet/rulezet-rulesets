import "hash"
rule IOC_NA_zip {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_NA_LAB"
    date_IOC   = "2023-11-14 04:21:40"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "NA"
    file_type  = "zip"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "929c3cadc1a37a6f11f9f2b473fa9518d3c4162480b90e517204842f1f809429" or
    hash.sha256(0, filesize) == "c0aa81cd918caf90384d90ebafbe293b25968bb1a6063d74e2ee998f471bb635" or
    hash.sha256(0, filesize) == "576f6ca3dae804a4f50f29d5e46731890f23998b77dd4bd0a5ef92ee58809bdb" or
    hash.sha256(0, filesize) == "95d14e055fde0847733890ca247d22a1ef9ad581389e6beead1de46d3147ff90" or
    hash.sha256(0, filesize) == "85899457d67ec7a33751203ce6af4f98699d6832f0cf0264db1163c21e70b8ba" or
    hash.sha256(0, filesize) == "b312181bf94aea26d5f11a6bc046b8e8858328f1c8ac2b199100a08d5c0d4e87" or
    hash.sha256(0, filesize) == "19b739c72921a6b24a4c9ae99f3371f2f25e4d6a7bab90c256a8c44e924f8e85" or
    hash.sha256(0, filesize) == "a7382872a48a55f433257999b847b4ba8c26bfa1a565a819967a410033aa346d" or
    hash.sha256(0, filesize) == "592f4ee0f178de6162247010bf85d4eaccfa123d8a26a9db120bea1e13a830cd" or
    hash.sha256(0, filesize) == "65cf59b3533759dd226925d14d2923b4ff5e6077518af382552cc01c6d98bafe" or
    hash.sha256(0, filesize) == "1847e53f0b2d743d51ee222f85372eb4dd452877635ed83f962d76c7293ebd74" or
    hash.sha256(0, filesize) == "253c97514805ad5ee0dab272a842169a639faccdd38ce24bf08054b49e2c9fe9" or
    hash.sha256(0, filesize) == "378a0fb9073a81918cdfc7a87508df39acfc751a9d646cab83cf7eee919081e0" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}