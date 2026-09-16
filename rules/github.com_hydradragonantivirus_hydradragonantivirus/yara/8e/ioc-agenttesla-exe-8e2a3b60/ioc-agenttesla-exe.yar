import "hash"
rule IOC_AGENTTESLA_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AGENTTESLA_LAB"
    date_IOC   = "2023-11-14 03:19:49"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AGENTTESLA"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "f873fc0535d38b4ced119b8d2d555e23496174f01b5747b148c50925c2f60424" or
    hash.sha256(0, filesize) == "cbebcef944dc8b96250fa57c98bef408a1f3f053f303871f89f8f3035b4b3e7a" or
    hash.sha256(0, filesize) == "00e245b9a6266afb2eb6b81cf96520ca093b7242dd39b1b74daf4d5811ce35fe" or
    hash.sha256(0, filesize) == "f112d1e7c8414255846131a14109ae12e45ad65296bd014601d0a83c9ea90cb2" or
    hash.sha256(0, filesize) == "f6b96b0e4ca1b30e8f8973036205314b80f9ac4ebff7f0e46c1c74d51c72202a" or
    hash.sha256(0, filesize) == "8c69f8ddbe47d5020425853ec7cc411a6656b7f411862d1de7f1081e1f6739c9" or
    hash.sha256(0, filesize) == "dbe5ea4fdeec96fa6dbd4e378dd10f4c6b89a921adaff45fe358f3dbb55da1fb" or
    hash.sha256(0, filesize) == "0f6154350e73fcd971f98f7bf3fd43773edd1cca24c16d259a4c755958970332" or
    hash.sha256(0, filesize) == "6398b922ae61c54c8ccc93725d584c8e3f0c3005716cd21fd63fb79e3bc78836" or
    hash.sha256(0, filesize) == "8632a6cdacd3c2ca44c427d1ef6bea4a9c16a7089a31f12fe79ba6e108860902" or
    hash.sha256(0, filesize) == "df5e129f51b16e5dec57270b57c8c742242d83d3fe7c556184cb004ef353eea5" or
    hash.sha256(0, filesize) == "b051fc9f064e736c6293b5f0d074f4fd3cbf145d0885b9a44539c8fbd4a15621" or
    hash.sha256(0, filesize) == "64cf760478ae702e8157d46821cfdb8fad6ac6bf640b511ca736d7315db70632" or
    hash.sha256(0, filesize) == "b1e5d0c3a97d2c9fd511f7991e33b2782f6dfc92ce9310e098e7fb53f6c4e3be" or
    hash.sha256(0, filesize) == "4dc4ade4ae2d4abc759ac2fd298eeca6a88f1669fb1f3e761c46d134b5620a0f" or
    hash.sha256(0, filesize) == "10f79a0bcff0aa1bd3c2ee942bb6894627ad897317413a354df70b50f4e0f56e" or
    hash.sha256(0, filesize) == "dc7b17accaba0cbe8edc9a22bf625eb3e74f64b6e17046175095e4197792bd98" or
    hash.sha256(0, filesize) == "5e32a7b5320ee9b3277092e547033be4d247629a4cfe396c19ed326bc2063210" or
    hash.sha256(0, filesize) == "ca75c3b3a4278d054eac12a4c06addf6b48ab936ed5a21f1ba652d0d209c0f97" or
    hash.sha256(0, filesize) == "c29c56a3681fb8d2f46ca4e7070f088e2e7c8f8b11c3d4218c79b91778c3536e" or
    hash.sha256(0, filesize) == "8af6097b2ebe610f5f0602bfc6f5414f797cfbaef62ebf522f8c93e1f23eadf5" or
    hash.sha256(0, filesize) == "259e6fc89c741d8f3a240402ffb767e833317bea4e190ba44e516adf63cd5b82" or
    hash.sha256(0, filesize) == "69e82246e2a2444321ad9c8c84a445b8ec6b18702c2407565cae60e07b3823ef" or
    hash.sha256(0, filesize) == "2d63c7065f4924e91461a07ccefafbddc4d7944cc5cbf0ad543a7c7f8103d36e" or
    hash.sha256(0, filesize) == "9df6347fd6d4c18024e5330a6d05ab03d7f85f7aa70d7f083bf80f764852a367" or
    hash.sha256(0, filesize) == "ee87b91b6480592bf45354a624ef6b478ed812f5ef33e36dbb6775fe057dbcfa" or
    hash.sha256(0, filesize) == "22e6002a6d91fa1b1776f6b2e1cea01312a95ba504643bead0deaa0b90e193eb" or
    hash.sha256(0, filesize) == "e3b762b0f49f604badd73ea22cd90861766a1568211b461ce08f687ff9d22f6f" or
    hash.sha256(0, filesize) == "a999fa0b2c139c85ebb6a33cc1785777a333ee9b491ca696d776887f6d0400bc" or
    hash.sha256(0, filesize) == "777c4e75052752ee1f5ccad536e28dc1bc5d8436892bbbcc86a7cf69d581ab8f" or
    hash.sha256(0, filesize) == "8645bdb895457e08db9625bba8903490cecaad66c6cd3c0af3688afa60a425c1" or
    hash.sha256(0, filesize) == "a245bbcd8bd89a1b4d24f79630212fed50905ac410132678fcea552048b66792" or
    hash.sha256(0, filesize) == "a3e10f92baec9fd3a6ac12cfdc393f4031a94b4843300a767e89b0dfbc026a6d" or
    hash.sha256(0, filesize) == "79b5b0596a21d1d0642a64198c45d8662e9eede03347ce5f50eaac73f31c32e7" or
    hash.sha256(0, filesize) == "b74c35fff28c2545faae06261ed6ee1649067638169ef24dfa449bb201fd6039" or
    hash.sha256(0, filesize) == "7a26f105efac6daa9226f4ab1b6bf0ff600fe2140da9fcf3e91e502ed359ee5f" or
    hash.sha256(0, filesize) == "da21ece2f4aa50ee504970a2fefed88038ade14bb3f68b0d6e388da6f40628c9" or
    hash.sha256(0, filesize) == "fa86b4d3e3e4217d2c502925eb6c41fb7a9bf0a17a976fc6a11a849d5861c8d0" or
    hash.sha256(0, filesize) == "aa7afebfd032006687eddefc5578bbc1933f1477aeaef5a17427677a4de08d95" or
    hash.sha256(0, filesize) == "db5791df9f9164152525e6564a5984cc23ff98593c92d0ad167b8d7fbb0e3111" or
    hash.sha256(0, filesize) == "047575bd81b3dc7b788d1f33b92ccd8e42804e7bb9b578246a1284d0e565a6b9" or
    hash.sha256(0, filesize) == "421bff513232de6adf60e78f45df28ed50b3897a27570596e12f661d2bb4e8d9" or
    hash.sha256(0, filesize) == "50174c869349bc2bbb082345c016fb75442f9858a91208180f5ca49ada8e9c5d" or
    hash.sha256(0, filesize) == "f1a6e53beb7e03091a732ba8d1093eb5162dd620c85f7ee44bdc6efe25c3c853" or
    hash.sha256(0, filesize) == "e250eef1eaea9092ecaa3ecd7a94b02720a9fb2aadd9c8a3b234e52ed7710ae8" or
    hash.sha256(0, filesize) == "2772267437ac2a4a39e1c4893788b420e3eafd75c0517c3d8bb58516c8e2b196" or
    hash.sha256(0, filesize) == "f29177a4cfd69578f868616ce53b974ee5c362b2d43e70a17277ac18bbe4d125" or
    hash.sha256(0, filesize) == "76b695c17786615cfe769077dde4f7d7dae83e8a6f638680c9e0e59b8d1f582c" or
    hash.sha256(0, filesize) == "91b0829c56341b5ebe30e0b59b263f8d174bcf4b1718bbfe5cb18b7faa2d606f" or
    hash.sha256(0, filesize) == "c073d55e30e424b99d07e376c38ca35b579dbd327da6be96cec527b0e3132ccd" or
    hash.sha256(0, filesize) == "cb15630de2fc38b0f07691ab16cfebcc1a6a940c867c0fc41a811c26525d9fc4" or
    hash.sha256(0, filesize) == "d8c86642c4e7e86d3591143c9bd7a7ca0278ed8812908b81e5633948ebee2eee" or
    hash.sha256(0, filesize) == "780864eca14f5609a0466e0831fd4ea929247f1bc6768ef0aabbb4a12135b319" or
    hash.sha256(0, filesize) == "7c694dd1d56f0082c40c850df23deb92f994cabc5af5a391f52e7e1702b50def" or
    hash.sha256(0, filesize) == "c804d3785acf26364471c13ee7b8714bce6329666877dff5541252ae0613af55" or
    hash.sha256(0, filesize) == "9b1a04a9a7488c5c618d00ee10920203d5bb51cc2c3470aae460f7a971a44843" or
    hash.sha256(0, filesize) == "8992f05844656419027980e08a09950c5162846b52277dc662b4866dcfa18871" or
    hash.sha256(0, filesize) == "e0a14b9acddbf73d270c2eabf671ce58e1c2aaa237ccf2de320efedc947b6ccc" or
    hash.sha256(0, filesize) == "899c4c78e96a4c19a650d2cad2ad6b7e358bc78f42c9ba9407821e0be43347f6" or
    hash.sha256(0, filesize) == "c49d3c572cd0b818ced382d46198cd833015f79459b10e2cb4caee1bd18f5e72" or
    hash.sha256(0, filesize) == "1e6327a5456f3aac77ec28cc80c9f9f8cff8a157a25a8a2f597764dcbccce3ea" or
    hash.sha256(0, filesize) == "e90446f4637905f90836fe5c684ac38531090b2f64bb561a555e09cb4af076fc" or
    hash.sha256(0, filesize) == "e5a39d95388a1324e37c31b9bc6a527941dd0c0736a0971ead7ec611474d2eb7" or
    hash.sha256(0, filesize) == "1e1a3828028401c6052fd951935347159121c19c01e7dc47fa2d4620a60c720d" or
    hash.sha256(0, filesize) == "6c3aa6c7804d75cd98888500430589c9996bd681881fdac1850590343ab4d13d" or
    hash.sha256(0, filesize) == "4ae304d194dbeac326186c31c58bbf4f4c87791ddbb048efc34854e75dde91bc" or
    hash.sha256(0, filesize) == "7a04dd7893f89eeffa0df553493f9a5367bf08e041c4989888e84d7006a65a65" or
    hash.sha256(0, filesize) == "57454ca5dffc314f665767b53dde6778afe2ef9b3470eadc71ada2130854ab2d" or
    hash.sha256(0, filesize) == "73a225250c2ccdff194478cd7d7aa96a04b314c6fbdf105183198548a0f93684" or
    hash.sha256(0, filesize) == "aebcd6039f3bfcf9ddfadaee2d5e631afb676e36e1497036283b24c73b810800" or
    hash.sha256(0, filesize) == "f45cce1292aa30dc88decc03fe81e7c10a64e4302eb1e3faa81c385e36d2a1ff" or
    hash.sha256(0, filesize) == "3f0f2b7e3062679b5ba9559637eee1d3ab15dea790fbf3c85b69fcccb3edc8bf" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}